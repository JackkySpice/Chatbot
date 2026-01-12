.class public final synthetic Landroidx/appcompat/view/menu/rb;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Landroid/animation/ValueAnimator$AnimatorUpdateListener;


# instance fields
.field public final synthetic a:Landroidx/appcompat/view/menu/ub;


# direct methods
.method public synthetic constructor <init>(Landroidx/appcompat/view/menu/ub;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Landroidx/appcompat/view/menu/rb;->a:Landroidx/appcompat/view/menu/ub;

    return-void
.end method


# virtual methods
.method public final onAnimationUpdate(Landroid/animation/ValueAnimator;)V
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/rb;->a:Landroidx/appcompat/view/menu/ub;

    invoke-static {v0, p1}, Landroidx/appcompat/view/menu/ub;->x(Landroidx/appcompat/view/menu/ub;Landroid/animation/ValueAnimator;)V

    return-void
.end method
