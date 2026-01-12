.class public Landroidx/appcompat/view/menu/wm$f;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/lang/Runnable;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Landroidx/appcompat/view/menu/wm;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = "f"
.end annotation


# instance fields
.field public final synthetic m:Landroidx/appcompat/view/menu/wm;


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/wm;)V
    .locals 0

    iput-object p1, p0, Landroidx/appcompat/view/menu/wm$f;->m:Landroidx/appcompat/view/menu/wm;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public a()V
    .locals 2

    iget-object v0, p0, Landroidx/appcompat/view/menu/wm$f;->m:Landroidx/appcompat/view/menu/wm;

    const/4 v1, 0x0

    iput-object v1, v0, Landroidx/appcompat/view/menu/wm;->l:Landroidx/appcompat/view/menu/wm$f;

    invoke-virtual {v0, p0}, Landroid/view/View;->removeCallbacks(Ljava/lang/Runnable;)Z

    return-void
.end method

.method public b()V
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/wm$f;->m:Landroidx/appcompat/view/menu/wm;

    invoke-virtual {v0, p0}, Landroid/view/View;->post(Ljava/lang/Runnable;)Z

    return-void
.end method

.method public run()V
    .locals 2

    iget-object v0, p0, Landroidx/appcompat/view/menu/wm$f;->m:Landroidx/appcompat/view/menu/wm;

    const/4 v1, 0x0

    iput-object v1, v0, Landroidx/appcompat/view/menu/wm;->l:Landroidx/appcompat/view/menu/wm$f;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/wm;->drawableStateChanged()V

    return-void
.end method
