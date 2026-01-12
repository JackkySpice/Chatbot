.class public final Landroidx/appcompat/view/menu/x52;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic m:Landroidx/appcompat/view/menu/ts1;

.field public final synthetic n:Landroidx/appcompat/view/menu/z52;


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/z52;Landroidx/appcompat/view/menu/ts1;)V
    .locals 0

    iput-object p1, p0, Landroidx/appcompat/view/menu/x52;->n:Landroidx/appcompat/view/menu/z52;

    iput-object p2, p0, Landroidx/appcompat/view/menu/x52;->m:Landroidx/appcompat/view/menu/ts1;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final run()V
    .locals 3

    iget-object v0, p0, Landroidx/appcompat/view/menu/x52;->n:Landroidx/appcompat/view/menu/z52;

    monitor-enter v0

    :try_start_0
    iget-object v1, p0, Landroidx/appcompat/view/menu/x52;->n:Landroidx/appcompat/view/menu/z52;

    const/4 v2, 0x0

    invoke-static {v1, v2}, Landroidx/appcompat/view/menu/z52;->c(Landroidx/appcompat/view/menu/z52;Z)V

    iget-object v1, p0, Landroidx/appcompat/view/menu/x52;->n:Landroidx/appcompat/view/menu/z52;

    iget-object v1, v1, Landroidx/appcompat/view/menu/z52;->n:Landroidx/appcompat/view/menu/d42;

    invoke-virtual {v1}, Landroidx/appcompat/view/menu/d42;->c0()Z

    move-result v1

    if-nez v1, :cond_0

    iget-object v1, p0, Landroidx/appcompat/view/menu/x52;->n:Landroidx/appcompat/view/menu/z52;

    iget-object v1, v1, Landroidx/appcompat/view/menu/z52;->n:Landroidx/appcompat/view/menu/d42;

    invoke-virtual {v1}, Landroidx/appcompat/view/menu/bz1;->l()Landroidx/appcompat/view/menu/lt1;

    move-result-object v1

    invoke-virtual {v1}, Landroidx/appcompat/view/menu/lt1;->K()Landroidx/appcompat/view/menu/ot1;

    move-result-object v1

    const-string v2, "Connected to service"

    invoke-virtual {v1, v2}, Landroidx/appcompat/view/menu/ot1;->a(Ljava/lang/String;)V

    iget-object v1, p0, Landroidx/appcompat/view/menu/x52;->n:Landroidx/appcompat/view/menu/z52;

    iget-object v1, v1, Landroidx/appcompat/view/menu/z52;->n:Landroidx/appcompat/view/menu/d42;

    iget-object v2, p0, Landroidx/appcompat/view/menu/x52;->m:Landroidx/appcompat/view/menu/ts1;

    invoke-virtual {v1, v2}, Landroidx/appcompat/view/menu/d42;->J(Landroidx/appcompat/view/menu/ts1;)V

    goto :goto_0

    :catchall_0
    move-exception v1

    goto :goto_1

    :cond_0
    :goto_0
    monitor-exit v0

    return-void

    :goto_1
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    throw v1
.end method
