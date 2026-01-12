.class public final Landroidx/appcompat/view/menu/v12;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic m:Ljava/util/concurrent/atomic/AtomicReference;

.field public final synthetic n:Ljava/lang/String;

.field public final synthetic o:Ljava/lang/String;

.field public final synthetic p:Ljava/lang/String;

.field public final synthetic q:Landroidx/appcompat/view/menu/zz1;


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/zz1;Ljava/util/concurrent/atomic/AtomicReference;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V
    .locals 0

    iput-object p1, p0, Landroidx/appcompat/view/menu/v12;->q:Landroidx/appcompat/view/menu/zz1;

    iput-object p2, p0, Landroidx/appcompat/view/menu/v12;->m:Ljava/util/concurrent/atomic/AtomicReference;

    const/4 p1, 0x0

    iput-object p1, p0, Landroidx/appcompat/view/menu/v12;->n:Ljava/lang/String;

    iput-object p4, p0, Landroidx/appcompat/view/menu/v12;->o:Ljava/lang/String;

    iput-object p5, p0, Landroidx/appcompat/view/menu/v12;->p:Ljava/lang/String;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final run()V
    .locals 5

    iget-object v0, p0, Landroidx/appcompat/view/menu/v12;->q:Landroidx/appcompat/view/menu/zz1;

    iget-object v0, v0, Landroidx/appcompat/view/menu/bz1;->a:Landroidx/appcompat/view/menu/yw1;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/yw1;->J()Landroidx/appcompat/view/menu/d42;

    move-result-object v0

    iget-object v1, p0, Landroidx/appcompat/view/menu/v12;->m:Ljava/util/concurrent/atomic/AtomicReference;

    iget-object v2, p0, Landroidx/appcompat/view/menu/v12;->o:Ljava/lang/String;

    iget-object v3, p0, Landroidx/appcompat/view/menu/v12;->p:Ljava/lang/String;

    const/4 v4, 0x0

    invoke-virtual {v0, v1, v4, v2, v3}, Landroidx/appcompat/view/menu/d42;->S(Ljava/util/concurrent/atomic/AtomicReference;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    return-void
.end method
