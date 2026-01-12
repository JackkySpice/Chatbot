.class public final Landroidx/appcompat/view/menu/q12;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic m:J

.field public final synthetic n:Landroidx/appcompat/view/menu/zz1;


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/zz1;J)V
    .locals 0

    iput-object p1, p0, Landroidx/appcompat/view/menu/q12;->n:Landroidx/appcompat/view/menu/zz1;

    iput-wide p2, p0, Landroidx/appcompat/view/menu/q12;->m:J

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final run()V
    .locals 4

    iget-object v0, p0, Landroidx/appcompat/view/menu/q12;->n:Landroidx/appcompat/view/menu/zz1;

    iget-wide v1, p0, Landroidx/appcompat/view/menu/q12;->m:J

    const/4 v3, 0x1

    invoke-virtual {v0, v1, v2, v3}, Landroidx/appcompat/view/menu/zz1;->E(JZ)V

    iget-object v0, p0, Landroidx/appcompat/view/menu/q12;->n:Landroidx/appcompat/view/menu/zz1;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/dr1;->t()Landroidx/appcompat/view/menu/d42;

    move-result-object v0

    new-instance v1, Ljava/util/concurrent/atomic/AtomicReference;

    invoke-direct {v1}, Ljava/util/concurrent/atomic/AtomicReference;-><init>()V

    invoke-virtual {v0, v1}, Landroidx/appcompat/view/menu/d42;->Q(Ljava/util/concurrent/atomic/AtomicReference;)V

    return-void
.end method
