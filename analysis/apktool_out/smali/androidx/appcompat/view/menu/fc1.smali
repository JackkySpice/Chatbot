.class public final Landroidx/appcompat/view/menu/fc1;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic m:Landroidx/appcompat/view/menu/ic1;


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/ic1;)V
    .locals 0

    iput-object p1, p0, Landroidx/appcompat/view/menu/fc1;->m:Landroidx/appcompat/view/menu/ic1;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final run()V
    .locals 3

    iget-object v0, p0, Landroidx/appcompat/view/menu/fc1;->m:Landroidx/appcompat/view/menu/ic1;

    invoke-static {v0}, Landroidx/appcompat/view/menu/ic1;->v2(Landroidx/appcompat/view/menu/ic1;)Landroidx/appcompat/view/menu/hc1;

    move-result-object v0

    new-instance v1, Landroidx/appcompat/view/menu/df;

    const/4 v2, 0x4

    invoke-direct {v1, v2}, Landroidx/appcompat/view/menu/df;-><init>(I)V

    invoke-interface {v0, v1}, Landroidx/appcompat/view/menu/hc1;->c(Landroidx/appcompat/view/menu/df;)V

    return-void
.end method
