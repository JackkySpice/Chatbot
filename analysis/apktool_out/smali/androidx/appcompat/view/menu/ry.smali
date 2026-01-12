.class public final Landroidx/appcompat/view/menu/ry;
.super Landroidx/appcompat/view/menu/sy;
.source "SourceFile"


# instance fields
.field private volatile _immediate:Landroidx/appcompat/view/menu/ry;

.field public final o:Landroid/os/Handler;

.field public final p:Ljava/lang/String;

.field public final q:Z

.field public final r:Landroidx/appcompat/view/menu/ry;


# direct methods
.method public constructor <init>(Landroid/os/Handler;Ljava/lang/String;)V
    .locals 1

    const/4 v0, 0x0

    .line 4
    invoke-direct {p0, p1, p2, v0}, Landroidx/appcompat/view/menu/ry;-><init>(Landroid/os/Handler;Ljava/lang/String;Z)V

    return-void
.end method

.method public synthetic constructor <init>(Landroid/os/Handler;Ljava/lang/String;ILandroidx/appcompat/view/menu/kj;)V
    .locals 0

    and-int/lit8 p3, p3, 0x2

    if-eqz p3, :cond_0

    const/4 p2, 0x0

    .line 3
    :cond_0
    invoke-direct {p0, p1, p2}, Landroidx/appcompat/view/menu/ry;-><init>(Landroid/os/Handler;Ljava/lang/String;)V

    return-void
.end method

.method public constructor <init>(Landroid/os/Handler;Ljava/lang/String;Z)V
    .locals 1

    const/4 v0, 0x0

    .line 1
    invoke-direct {p0, v0}, Landroidx/appcompat/view/menu/sy;-><init>(Landroidx/appcompat/view/menu/kj;)V

    iput-object p1, p0, Landroidx/appcompat/view/menu/ry;->o:Landroid/os/Handler;

    iput-object p2, p0, Landroidx/appcompat/view/menu/ry;->p:Ljava/lang/String;

    iput-boolean p3, p0, Landroidx/appcompat/view/menu/ry;->q:Z

    if-eqz p3, :cond_0

    move-object v0, p0

    :cond_0
    iput-object v0, p0, Landroidx/appcompat/view/menu/ry;->_immediate:Landroidx/appcompat/view/menu/ry;

    iget-object p3, p0, Landroidx/appcompat/view/menu/ry;->_immediate:Landroidx/appcompat/view/menu/ry;

    if-nez p3, :cond_1

    .line 2
    new-instance p3, Landroidx/appcompat/view/menu/ry;

    const/4 v0, 0x1

    invoke-direct {p3, p1, p2, v0}, Landroidx/appcompat/view/menu/ry;-><init>(Landroid/os/Handler;Ljava/lang/String;Z)V

    iput-object p3, p0, Landroidx/appcompat/view/menu/ry;->_immediate:Landroidx/appcompat/view/menu/ry;

    :cond_1
    iput-object p3, p0, Landroidx/appcompat/view/menu/ry;->r:Landroidx/appcompat/view/menu/ry;

    return-void
.end method


# virtual methods
.method public A(Landroidx/appcompat/view/menu/jh;Ljava/lang/Runnable;)V
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/ry;->o:Landroid/os/Handler;

    invoke-virtual {v0, p2}, Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z

    move-result v0

    if-nez v0, :cond_0

    invoke-virtual {p0, p1, p2}, Landroidx/appcompat/view/menu/ry;->H(Landroidx/appcompat/view/menu/jh;Ljava/lang/Runnable;)V

    :cond_0
    return-void
.end method

.method public D(Landroidx/appcompat/view/menu/jh;)Z
    .locals 1

    iget-boolean p1, p0, Landroidx/appcompat/view/menu/ry;->q:Z

    if-eqz p1, :cond_1

    invoke-static {}, Landroid/os/Looper;->myLooper()Landroid/os/Looper;

    move-result-object p1

    iget-object v0, p0, Landroidx/appcompat/view/menu/ry;->o:Landroid/os/Handler;

    invoke-virtual {v0}, Landroid/os/Handler;->getLooper()Landroid/os/Looper;

    move-result-object v0

    invoke-static {p1, v0}, Landroidx/appcompat/view/menu/x50;->a(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p1

    if-nez p1, :cond_0

    goto :goto_0

    :cond_0
    const/4 p1, 0x0

    goto :goto_1

    :cond_1
    :goto_0
    const/4 p1, 0x1

    :goto_1
    return p1
.end method

.method public bridge synthetic F()Landroidx/appcompat/view/menu/na0;
    .locals 1

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/ry;->I()Landroidx/appcompat/view/menu/ry;

    move-result-object v0

    return-object v0
.end method

.method public final H(Landroidx/appcompat/view/menu/jh;Ljava/lang/Runnable;)V
    .locals 3

    new-instance v0, Ljava/util/concurrent/CancellationException;

    new-instance v1, Ljava/lang/StringBuilder;

    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    const-string v2, "The task was rejected, the handler underlying the dispatcher \'"

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v2, "\' was closed"

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-direct {v0, v1}, Ljava/util/concurrent/CancellationException;-><init>(Ljava/lang/String;)V

    invoke-static {p1, v0}, Landroidx/appcompat/view/menu/u60;->c(Landroidx/appcompat/view/menu/jh;Ljava/util/concurrent/CancellationException;)V

    invoke-static {}, Landroidx/appcompat/view/menu/em;->b()Landroidx/appcompat/view/menu/mh;

    move-result-object v0

    invoke-virtual {v0, p1, p2}, Landroidx/appcompat/view/menu/mh;->A(Landroidx/appcompat/view/menu/jh;Ljava/lang/Runnable;)V

    return-void
.end method

.method public I()Landroidx/appcompat/view/menu/ry;
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/ry;->r:Landroidx/appcompat/view/menu/ry;

    return-object v0
.end method

.method public equals(Ljava/lang/Object;)Z
    .locals 1

    instance-of v0, p1, Landroidx/appcompat/view/menu/ry;

    if-eqz v0, :cond_0

    check-cast p1, Landroidx/appcompat/view/menu/ry;

    iget-object p1, p1, Landroidx/appcompat/view/menu/ry;->o:Landroid/os/Handler;

    iget-object v0, p0, Landroidx/appcompat/view/menu/ry;->o:Landroid/os/Handler;

    if-ne p1, v0, :cond_0

    const/4 p1, 0x1

    goto :goto_0

    :cond_0
    const/4 p1, 0x0

    :goto_0
    return p1
.end method

.method public hashCode()I
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/ry;->o:Landroid/os/Handler;

    invoke-static {v0}, Ljava/lang/System;->identityHashCode(Ljava/lang/Object;)I

    move-result v0

    return v0
.end method

.method public toString()Ljava/lang/String;
    .locals 2

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/na0;->G()Ljava/lang/String;

    move-result-object v0

    if-nez v0, :cond_1

    iget-object v0, p0, Landroidx/appcompat/view/menu/ry;->p:Ljava/lang/String;

    if-nez v0, :cond_0

    iget-object v0, p0, Landroidx/appcompat/view/menu/ry;->o:Landroid/os/Handler;

    invoke-virtual {v0}, Landroid/os/Handler;->toString()Ljava/lang/String;

    move-result-object v0

    :cond_0
    iget-boolean v1, p0, Landroidx/appcompat/view/menu/ry;->q:Z

    if-eqz v1, :cond_1

    new-instance v1, Ljava/lang/StringBuilder;

    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v0, ".immediate"

    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    :cond_1
    return-object v0
.end method
