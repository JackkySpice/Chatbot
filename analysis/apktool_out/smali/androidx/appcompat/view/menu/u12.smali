.class public final Landroidx/appcompat/view/menu/u12;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic m:Ljava/util/concurrent/atomic/AtomicReference;

.field public final synthetic n:Ljava/lang/String;

.field public final synthetic o:Ljava/lang/String;

.field public final synthetic p:Ljava/lang/String;

.field public final synthetic q:Z

.field public final synthetic r:Landroidx/appcompat/view/menu/zz1;


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/zz1;Ljava/util/concurrent/atomic/AtomicReference;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V
    .locals 0

    iput-object p1, p0, Landroidx/appcompat/view/menu/u12;->r:Landroidx/appcompat/view/menu/zz1;

    iput-object p2, p0, Landroidx/appcompat/view/menu/u12;->m:Ljava/util/concurrent/atomic/AtomicReference;

    const/4 p1, 0x0

    iput-object p1, p0, Landroidx/appcompat/view/menu/u12;->n:Ljava/lang/String;

    iput-object p4, p0, Landroidx/appcompat/view/menu/u12;->o:Ljava/lang/String;

    iput-object p5, p0, Landroidx/appcompat/view/menu/u12;->p:Ljava/lang/String;

    iput-boolean p6, p0, Landroidx/appcompat/view/menu/u12;->q:Z

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final run()V
    .locals 7

    iget-object v0, p0, Landroidx/appcompat/view/menu/u12;->r:Landroidx/appcompat/view/menu/zz1;

    iget-object v0, v0, Landroidx/appcompat/view/menu/bz1;->a:Landroidx/appcompat/view/menu/yw1;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/yw1;->J()Landroidx/appcompat/view/menu/d42;

    move-result-object v1

    iget-object v2, p0, Landroidx/appcompat/view/menu/u12;->m:Ljava/util/concurrent/atomic/AtomicReference;

    const/4 v3, 0x0

    iget-object v4, p0, Landroidx/appcompat/view/menu/u12;->o:Ljava/lang/String;

    iget-object v5, p0, Landroidx/appcompat/view/menu/u12;->p:Ljava/lang/String;

    iget-boolean v6, p0, Landroidx/appcompat/view/menu/u12;->q:Z

    invoke-virtual/range {v1 .. v6}, Landroidx/appcompat/view/menu/d42;->T(Ljava/util/concurrent/atomic/AtomicReference;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    return-void
.end method
